import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { User } from '../users/entities/user.entity';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { EmailService } from '../email/email.service';
import { MoreThan } from 'typeorm';
@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private jwtService: JwtService,
    private emailService: EmailService,
  ) {}

  async signup(signupDto: SignupDto) {
    const existingUser = await this.usersRepository.findOne({
      where: { email: signupDto.email },
    });

    if (existingUser) {
      throw new BadRequestException({
        message: ['Email already exists'],
        error: 'Bad Request',
        statusCode: 400,
      });
    }

    const hashedPassword = await bcrypt.hash(signupDto.password, 10);
    const verificationToken = crypto.randomBytes(32).toString('hex');

    const user = this.usersRepository.create({
      ...signupDto,
      password: hashedPassword,
      emailVerificationToken: verificationToken,
    });

    await this.usersRepository.save(user);
    await this.emailService.sendVerificationEmail(user.email, verificationToken);

    return {
      message: ['User created successfully. Please verify your email.'],
      error: null,
      statusCode: 201,
    };
  }

  async login(loginDto: LoginDto) {
    const user = await this.usersRepository.findOne({
      where: { email: loginDto.email },
    });

    console.log(user)

    if (!user || !(await bcrypt.compare(loginDto.password, user.password))) {
      throw new UnauthorizedException({
        message: ['Invalid credentials'],
        error: 'Unauthorized',
        statusCode: 401,
      });
    }

    if (!user.isEmailVerified) {
      throw new UnauthorizedException({
        message: ['Please verify your email first'],
        error: 'Unauthorized',
        statusCode: 401,
      });
    }

    const payload = { sub: user.id, email: user.email };
    return {
      message: ['Login successful'],
      error: null,
      statusCode: 201,
      data: {
        access_token: await this.jwtService.signAsync(payload),
      },
    };
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const user = await this.usersRepository.findOne({
      where: { email: forgotPasswordDto.email },
    });

    if (!user) {
      throw new BadRequestException({
        message: ['User not found'],
        error: 'Bad Request',
        statusCode: 400,
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour

    user.passwordResetToken = resetToken;
    user.passwordResetExpires = resetTokenExpiry;
    await this.usersRepository.save(user);

    await this.emailService.sendPasswordResetEmail(user.email, resetToken);

    return {
      message: ['Password reset email sent'],
      error: null,
      statusCode: 200,
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const user = await this.usersRepository.findOne({
      where: {
        passwordResetToken: resetPasswordDto.token,
        passwordResetExpires: MoreThan(new Date()),
      },
    });

    if (!user) {
      throw new BadRequestException({
        message: ['Invalid or expired reset token'],
        error: 'Bad Request',
        statusCode: 400,
      });
    }

    user.password = await bcrypt.hash(resetPasswordDto.newPassword, 10);
    user.passwordResetToken = null;
    user.passwordResetExpires = null;
    await this.usersRepository.save(user);

    return {
      message: ['Password reset successful'],
      error: null,
      statusCode: 200,
    };
  }

  async verifyEmail(token: string) {
    const user = await this.usersRepository.findOne({
      where: { emailVerificationToken: token },
    });

    if (!user) {
      throw new BadRequestException({
        message: ['Invalid verification token'],
        error: 'Bad Request',
        statusCode: 400,
      });
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = null;
    await this.usersRepository.save(user);

    return {
      message: ['Email verified successfully'],
      error: null,
      statusCode: 200,
    };
  }
} 