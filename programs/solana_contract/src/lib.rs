use anchor_lang::prelude::*;
use anchor_spl::token::{TokenAccount, Token, Mint};
use anchor_spl::token::spl_token;

declare_id!("4ambXgqJSwqyUVK3G2Fu4Nx9PiKZ6822HrQH9hfZVofH");

#[program]
pub mod solana_contract {

    use spl_token::solana_program::stake::instruction::withdraw;

    use super::*;
   
    pub fn withdraw_token(ctx: Context<WithdrawToken>) -> Result<()> {
        let current_time = ctx.accounts.clock.unix_timestamp;

        let withdrawal_time = ctx.accounts.user_data.withdrawal_time;

        if current_time < withdrawal_time {
            return Err(ErrorCode::WithdrawalNotAllowed.into());
        }

        
        
    // Proceed with the withdrawal logic (token transfer)
    // Your token transfer logic goes here...

    // Ok(())
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
#[error_code]
pub enum ErrorCode {
    #[msg("Withdrawal not allowed before the chosen time.")]
    WithdrawalNotAllowed,
}
