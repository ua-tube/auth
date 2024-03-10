import { IsEmail, IsNotEmpty } from 'class-validator';

export class CreateRecoveryTokenDto {
  @IsNotEmpty()
  @IsEmail()
  public readonly email: string;
}
