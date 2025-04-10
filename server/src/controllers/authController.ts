import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

import { Role, User } from '@prisma/client';

import catchAsync from '../utils/catchAsync';
import AppError from '../utils/AppError';
import { loginSchema, signupSchema } from '../validators/authValidators';
import prisma from '../utils/prisma';
import { sendVerificationEmail } from '../utils/sendEmail';

const signToken = (user: User) => {
  return jwt.sign(user, process.env.JWT_SECRET as string, {
    expiresIn: (Number(process.env.JWT_EXPIRES_IN) || 90) * 24 * 60 * 60,
  });
};

const createSendToken = (user: User, statusCode: number, res: Response) => {
  const token = signToken(user);

  const cookieOptions = {
    expires: new Date(
      Date.now() +
        Number(process.env.JWT_COOKIE_EXPIRES_IN) * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none' as const,
  };

  const { password, verificationToken, ...userData } = user;

  res.cookie('jwt', token, cookieOptions).status(statusCode).json({
    status: 'success',
    data: userData,
  });
};

export const signup = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const zodResult = signupSchema.safeParse(req.body);

    if (!zodResult.success) {
      const errors = zodResult.error.errors.map((error) => error.message);
      return next(new AppError(errors.join(', '), 400));
    }

    const { name, email, password, confirmPassword, phone } = zodResult.data;

    if (password !== confirmPassword)
      return next(new AppError('Passwords do not match', 400));

    const hashedPassword = await bcrypt.hash(password, 12);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationTokenHash = crypto
      .createHash('sha256')
      .update(verificationToken)
      .digest('hex');

    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        role: Role.USER,
        phone,
        verificationToken: verificationTokenHash,
        passwordChangedAt: new Date(),
      },
    });

    sendVerificationEmail(newUser.name, newUser.email, verificationToken);
    createSendToken(newUser, 201, res);
  }
);

export const login = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const zodResult = loginSchema.safeParse(req.body);

    if (!zodResult.success) {
      const errors = zodResult.error.errors.map((error) => error.message);
      return next(new AppError(errors.join(', '), 400));
    }

    const { email, password } = zodResult.data;

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user || !(await bcrypt.compare(password, user.password)))
      return next(new AppError('Incorrect email or password', 401));

    if (!user.isVerified)
      return next(new AppError('Please verify your email first', 401));

    createSendToken(user, 200, res);
  }
);

export const verifyUser = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    if (!req.query.token) return next(new AppError('Token is required', 400));

    const hashedToken = crypto
      .createHash('sha256')
      .update(req.query.token as string)
      .digest('hex');

    const fetchedUser = await prisma.user.findFirst({
      where: { verificationToken: hashedToken },
    });

    if (!fetchedUser)
      return next(new AppError('Token is invalid or expired', 400));

    const updatedUser = await prisma.user.update({
      where: { id: fetchedUser.id },
      data: { isVerified: true, verificationToken: null },
    });

    createSendToken(updatedUser, 200, res);
  }
);
