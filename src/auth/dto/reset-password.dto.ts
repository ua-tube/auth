import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class ResetPasswordDto {
  @IsNotEmpty()
  @IsEmail()
  public readonly email: string;

  @IsNotEmpty()
  @Length(32, 32)
  @IsString()
  public readonly token: string;

  @IsNotEmpty()
  @Length(8, 64)
  @IsString()
  public readonly newPassword: string;
}
