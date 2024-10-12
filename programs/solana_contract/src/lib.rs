use anchor_lang::prelude::*;
use anchor_spl::token::spl_token;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use spl_token::solana_program::entrypoint::ProgramResult;

declare_id!("4ambXgqJSwqyUVK3G2Fu4Nx9PiKZ6822HrQH9hfZVofH");

#[program]
pub mod solana_contract {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, withdraw_time: i64) -> ProgramResult {
        ctx.accounts.user_data.withdrawal_time = withdraw_time;
        msg!(
            "Initialized user data with withdrawal time set to {}",
            withdraw_time
        );
        Ok(())
    }

    pub fn deposit_token(
        ctx: Context<DepositToken>,
        amount: u64,
        withdraw_time: i64,
        mint: Pubkey,
    ) -> ProgramResult {
        if ctx.accounts.user_token_account.mint != mint {
            return Err(ErrorCode::InvalidMint.into());
        }

        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.vault_token_account.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };

        ctx.accounts.user_data.withdrawal_time = withdraw_time;

        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

        token::transfer(cpi_ctx, amount)?;

        msg!(
            "Deposited {} tokens into vault at {:?} with timestamp {}",
            amount,
            ctx.accounts.vault_token_account.key(),
            ctx.accounts.user_data.withdrawal_time
        );

        Ok(())
    }

    pub fn withdraw_token(ctx: Context<WithdrawToken>, mint: Pubkey) -> ProgramResult {
        if ctx.accounts.user_token_account.mint != mint {
            return Err(ErrorCode::InvalidMint.into());
        }

        let current_time: i64 = ctx.accounts.clock.unix_timestamp;
        let withdrawal_time = ctx.accounts.user_data.withdrawal_time;

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
pub struct DepositToken<'info> {
    pub user: Signer<'info>, // User who is signing the transaction

    #[account(
        mut,
        associated_token::mint = mint,            // Ensures the user's token account holds tokens of this mint
        associated_token::authority = user,       // Ensures the user's token account is owned by the user
    )]
    pub user_token_account: Account<'info, TokenAccount>, // User's token account for deposit

    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],   // Derives the vault's PDA
        bump,
    )]
    pub vault_token_account: Account<'info, TokenAccount>, // Program's vault token account

    #[account(address = spl_token::id())]
    pub token_program: Program<'info, Token>, // Token program to facilitate SPL transfers

    pub system_program: Program<'info, System>, // System program

    pub rent: Sysvar<'info, Rent>, // Rent system variable (to manage account rent-exemption)

    #[account()]
    pub mint: Account<'info, Mint>, // Mint of the token being deposited

    pub user_data: Account<'info, UserData>, // User data account storing the withdrawal time
}

#[derive(Accounts)]
pub struct WithdrawToken<'info> {
    #[account(mut)]
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

    pub system_program: Program<'info, System>, // System program for basic instructions

    pub clock: Sysvar<'info, Clock>, // Clock sysvar to get current blockchain time

    #[account(mut)]
    pub user_data: Account<'info, UserData>, // User data account that stores the withdrawal time

    pub mint: Account<'info, Mint>, // Mint of the token being withdrawn
}

#[account]
pub struct UserData {
    pub withdrawal_time: i64, // The timestamp after which the user can withdraw tokens
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    pub user: Signer<'info>, // User who is signing the transaction

    #[account(
        mut,
        associated_token::mint = mint,            // Ensures the user's token account holds tokens of this mint
        associated_token::authority = user,       // Ensures the user's token account is owned by the user
    )]
    pub user_token_account: Account<'info, TokenAccount>, // User's token account for deposit

    #[account(address = spl_token::id())]
    pub token_program: Program<'info, Token>, // Token program to facilitate SPL transfers

    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],   // Derives the vault's PDA
        bump,
    )]
    pub vault_token_account: Account<'info, TokenAccount>, // Program's vault token account

    pub system_program: Program<'info, System>, // System program

    pub rent: Sysvar<'info, Rent>, // Rent system variable (to manage account rent-exemption)

    pub mint: Account<'info, Mint>, // Mint of the token being deposited

    pub user_data: Account<'info, UserData>, // User data account
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
            ErrorCode::InvalidMint => ProgramError::Custom(0),
            ErrorCode::WithdrawalNotAllowed => ProgramError::Custom(1),
        }
    }
}
