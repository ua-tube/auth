import { IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @IsNotEmpty()
  @IsString()
  public readonly email: string;

  @IsNotEmpty()
  @IsString()
  public readonly password: string;
}
