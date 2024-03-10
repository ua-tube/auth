import { User } from '@prisma/client';

export class UserInfoDto {
  public readonly id: string;
  public readonly email: string;

  constructor({ id, email }: User) {
    this.id = id;
    this.email = email;
  }
}
