import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class SignupDto {
  @IsNotEmpty()
  @IsEmail()
  public readonly email: string;

  @IsNotEmpty()
  @Length(8, 64)
  @IsString()
  public readonly password: string;
}
