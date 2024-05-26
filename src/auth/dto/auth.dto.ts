import {
  IsNotEmpty,
  IsNumberString,
  IsPhoneNumber,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class AuthDTO {
  @IsNotEmpty()
  @IsPhoneNumber()
  mobile: string;
}

export class LoginDTO {
  @IsNotEmpty()
  @IsPhoneNumber()
  mobile: string;

  @IsNotEmpty()
  @IsNumberString()
  @MaxLength(4)
  @MinLength(4)
  otp: string;
}
export class RegisterDTO {
  @IsNotEmpty()
  @IsPhoneNumber()
  mobile: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(4)
  @MaxLength(30)
  name: string;
}
