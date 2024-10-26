use anchor_lang::prelude::*;
use anchor_spl::token::spl_token;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use spl_token::solana_program::entrypoint::ProgramResult;

declare_id!("Ef5GU5wYGDREHsv58CqAXTffcQHNGZCGnBHGNcW7riP8");

#[program]
pub mod solana_contract {
    use super::*;

    pub fn initialize_vault(
        ctx: Context<InitializeVault>,
        duration: i64,
        vault_id: i64,
    ) -> ProgramResult {
        let vault_data = &mut ctx.accounts.vault_data;

        vault_data.withdrawal_time = Clock::get()?.unix_timestamp + duration;
        vault_data.vault_id = vault_id;

        msg!("Initialized");
        Ok(())
    }

    pub fn deposit_token(ctx: Context<DepositToken>, amount: u64, mint: Pubkey) -> ProgramResult {
        if ctx.accounts.user_token_account.mint != mint {
            return Err(ErrorCode::InvalidMint.into());
        }

        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.vault_token_account.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };

        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

        token::transfer(cpi_ctx, amount)?;

        msg!(
            "Deposited {} tokens into vault at {:?} with timestamp {}",
            amount,
            &ctx.accounts.vault_token_account.key(),
            &ctx.accounts.vault_data.withdrawal_time
        );

        Ok(())
    }

    pub fn withdraw_token(ctx: Context<WithdrawToken>, mint: Pubkey) -> ProgramResult {
        if ctx.accounts.user_token_account.mint != mint {
            return Err(ErrorCode::InvalidMint.into());
        }

        let current_time: i64 = ctx.accounts.clock.unix_timestamp;
        let withdrawal_time = ctx.accounts.vault_data.withdrawal_time;

        if current_time < withdrawal_time {
            return Err(ErrorCode::WithdrawalNotAllowed.into());
        }

        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token_account.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.token_program.to_account_info(),
        };

        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

        token::transfer(cpi_ctx, ctx.accounts.vault_token_account.amount)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(mut)]
    pub user: Signer<'info>, // User who is signing the transaction

    #[account()]
    pub user_token_account: Box<Account<'info, TokenAccount>>, // User's token account 2 make deposit from

    #[account(address = spl_token::id())]
    pub token_program: Program<'info, Token>,

    #[account(
        init,
        space = 8 + 8 + 8, // address + withdrawl + vault_id (8 bytes)
        payer = user,
    )]
    pub vault_data: Account<'info, VaultData>,

    #[account(
        init,
        payer = user,
        space = 8 + 96
    )]
    pub mint: Account<'info, Mint>,

    #[account(
        init,
        token::mint = mint,
        token::authority = user,
        payer = user,
        seeds = [b"vault", user.key().as_ref(),  &vault_data.vault_id.to_le_bytes()],   
        bump,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
    pub clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
pub struct DepositToken<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account()]
    pub user_token_account: Account<'info, TokenAccount>, // User's token account for deposit

    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],   // Derives the vault's PDA
        bump,
    )]
    pub vault_token_account: Account<'info, TokenAccount>, // Program's vault token account

    #[account(address = spl_token::id())]
    pub token_program: Program<'info, Token>, // Token program to facilitate SPL transfers

    pub vault_data: Account<'info, VaultData>, // User data account storing the withdrawal time
}

#[derive(Accounts)]
pub struct WithdrawToken<'info> {
    pub user: Signer<'info>, // User signing the transaction

    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>, // User's token account to receive withdrawn tokens

    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump,
    )]
    pub vault_token_account: Account<'info, TokenAccount>, // Program's vault token account holding tokens

    #[account(address = spl_token::id())]
    pub token_program: Program<'info, Token>, // Token program to facilitate SPL transfers

    pub clock: Sysvar<'info, Clock>, // Clock sysvar to get current blockchain time

    pub vault_data: Account<'info, VaultData>, // User data account that stores the withdrawal time
}

#[account]
pub struct VaultData {
    pub withdrawal_time: i64,
    pub vault_id: i64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Withdrawal not allowed before the chosen time.")]
    WithdrawalNotAllowed,
    #[msg("Invalid Mint, change token.")]
    InvalidMint,
}

impl From<ErrorCode> for ProgramError {
    fn from(e: ErrorCode) -> ProgramError {
        match e {
            ErrorCode::InvalidMint => ProgramError::Custom(e as u32 + 6000),
            ErrorCode::WithdrawalNotAllowed => ProgramError::Custom(e as u32 + 6000),
        }
    }
}
