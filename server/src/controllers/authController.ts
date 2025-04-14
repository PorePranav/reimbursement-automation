import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt, { JwtPayload } from 'jsonwebtoken';
import crypto from 'crypto';

import { Role, User, UserCategory } from '@prisma/client';

import catchAsync from '../utils/catchAsync';
import AppError from '../utils/AppError';
import { loginSchema, signupSchema } from '../validators/authValidators';
import prisma from '../utils/prisma';
import {
  sendPasswordResetMail,
  sendVerificationEmail,
} from '../utils/sendEmail';

const signToken = (user: User) => {
  const { id, role, userCategory, isVerified, isKycComplete } = user;
  return jwt.sign(
    { id, role, userCategory, isVerified, isKycComplete },
    process.env.JWT_SECRET as string,
    {
      expiresIn: (Number(process.env.JWT_EXPIRES_IN) || 90) * 24 * 60 * 60,
    }
  );
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

    const { name, email, password, confirmPassword, phone, userCategory } =
      zodResult.data;

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
        userCategory,
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

export const forgotPassword = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    if (!req.body.email) {
      return next(new AppError('Please provide your email address', 400));
    }

    const fetchedUser = await prisma.user.findFirst({
      where: { email: req.body.email },
    });

    if (!fetchedUser) {
      return next(
        new AppError('There is no user with that email address', 404)
      );
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    await prisma.user.update({
      where: { id: fetchedUser.id },
      data: {
        passwordResetToken: resetTokenHash,
        passwordResetTokenExpiresAt: new Date(Date.now() + 10 * 60 * 1000),
      },
    });

    sendPasswordResetMail(fetchedUser.name, fetchedUser.email, resetToken);

    res.status(200).json({
      status: 'success',
    });
  }
);

export const resetPassword = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    if (!req.query.token) return next(new AppError('Token is required', 400));

    const hashedToken = crypto
      .createHash('sha256')
      .update(req.query.token as string)
      .digest('hex');

    const fetchedUser = await prisma.user.findFirst({
      where: {
        passwordResetToken: hashedToken,
        passwordResetTokenExpiresAt: { gt: new Date() },
      },
    });

    if (!fetchedUser)
      return next(new AppError('Token is invalid or has expired', 400));

    if (req.body.password !== req.body.confirmPassword)
      return next(new AppError('Passwords do not match', 400));

    const hashedPassword = await bcrypt.hash(req.body.password, 12);

    const updatedUser = await prisma.user.update({
      where: { id: fetchedUser.id },
      data: {
        password: hashedPassword,
        passwordResetToken: null,
        passwordResetTokenExpiresAt: null,
      },
    });

    createSendToken(updatedUser, 200, res);
  }
);

export const changePassword = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    if (
      !req.body.currentPassword ||
      !req.body.newPassword ||
      !req.body.confirmPassword
    ) {
      return next(
        new AppError(
          'Please provide your current password and new password',
          400
        )
      );
    }

    if (req.body.newPassword !== req.body.confirmPassword) {
      return next(new AppError('Passwords do not match', 400));
    }

    const fetchedUser = await prisma.user.findUnique({
      where: { id: req.user!.id },
    });

    if (
      !(await bcrypt.compare(req.body.currentPassword, fetchedUser!.password))
    ) {
      return next(new AppError('Your current password is wrong', 401));
    }

    const updatedUser = await prisma.user.update({
      where: { id: fetchedUser!.id },
      data: {
        password: await bcrypt.hash(req.body.newPassword, 12),
      },
    });

    createSendToken(updatedUser, 200, res);
  }
);

export const createAdminUser = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token || token !== process.env.ADMIN_API_KEY)
      return next(
        new AppError('You are not authorized to perform this action', 403)
      );

    const zodResult = signupSchema.safeParse(req.body);

    if (!zodResult.success) {
      const errors = zodResult.error.errors.map((error) => error.message);
      return next(new AppError(errors.join(', '), 400));
    }

    const { name, email, password, confirmPassword, phone } = zodResult.data;

    if (password !== confirmPassword)
      return next(new AppError('Passwords do not match', 400));

    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        role: Role.ADMIN,
        userCategory: UserCategory.NA,
        isVerified: true,
        isKycComplete: true,
        phone,
      },
    });

    const { password: newUserPassword, ...data } = newUser;

    res.status(201).json({
      status: 'success',
      data,
    });
  }
);

export const createOperatorUser = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const zodResult = signupSchema.safeParse(req.body);

    if (!zodResult.success) {
      const errors = zodResult.error.errors.map((error) => error.message);
      return next(new AppError(errors.join(', '), 400));
    }

    const { name, email, password, confirmPassword } = zodResult.data;

    if (password !== confirmPassword)
      return next(new AppError('Passwords do not match', 400));

    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        role: Role.OPERATOR,
        userCategory: UserCategory.NA,
        isVerified: true,
        isKycComplete: true,
      },
    });

    const { password: newUserPassword, ...data } = newUser;

    res.status(201).json({
      status: 'success',
      data,
    });
  }
);

export const logout = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    res.clearCookie('jwt').status(200).json({
      status: 'success',
    });
  }
);

export const isLoggedIn = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    if (!req.cookies?.jwt)
      return next(new AppError('You are not logged in', 401));

    const decoded = (await jwt.verify(
      req.cookies.jwt,
      process.env.JWT_SECRET!
    )) as JwtPayload;

    const currentUser = await prisma.user.findUnique({
      where: {
        id: decoded.id,
      },
    });

    if (!currentUser) {
      return next(
        new AppError(
          'The user belonging to this token does no longer exist',
          401
        )
      );
    }

    const changedTimestamp = Math.floor(
      new Date(currentUser.passwordChangedAt!).getTime() / 1000
    );

    if (decoded.iat && changedTimestamp > decoded.iat) {
      return next(
        new AppError('User recently changed password! Please log in again', 401)
      );
    }

    res.status(200).json({
      status: 'success',
      data: currentUser,
    });
  }
);

export const protect = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies?.jwt;

    if (!token || token === null)
      return next(
        new AppError('You are not logged in! Please log in to get access.', 403)
      );

    const decodedUser = (await jwt.verify(
      token,
      process.env.JWT_SECRET!
    )) as User;

    if (!decodedUser.isVerified)
      return next(new AppError('Please verify your email first', 401));

    if (decodedUser.isKycComplete === false)
      return next(new AppError('Please complete your KYC first', 401));

    req.user = decodedUser as User;

    next();
  }
);

export const restrictTo = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!roles.includes(req.user!.role))
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );

    next();
  };
};
