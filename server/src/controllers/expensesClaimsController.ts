import { Request, Response, NextFunction } from 'express';

import prisma from '../utils/prisma';
import catchAsync from '../utils/catchAsync';
import AppError from '../utils/AppError';
import { Role, SanctionStatus, UserCategory } from '@prisma/client';
import {
  approveExpenseFormSchema,
  createExpenseFormSchema,
  reimburseExpenseFormSchema,
} from '../validators/expensesFormValidators';
import { stat } from 'fs';

export const protectExpense = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    if (
      req.user!.userCategory !== UserCategory.VENDOR &&
      !(req.user!.role === Role.ADMIN || req.user!.role === Role.OPERATOR)
    ) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }
    next();
  }
);

export const createExpenseForm = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const zodResult = createExpenseFormSchema.safeParse(req.body);

    const fetchedExpenseForm = await prisma.expensesForm.findFirst({
      where: {
        eventId: req.body.eventId,
        userId: req.user!.id,
      },
    });

    if (fetchedExpenseForm)
      return next(new AppError('Expense form already exists', 400));

    if (!zodResult.success) {
      const errors = zodResult.error.errors.map((error) => error.message);
      return next(new AppError(errors.join(', '), 400));
    }

    const fetchedEvent = await prisma.event.findUnique({
      where: {
        id: zodResult.data.eventId,
      },
    });

    if (!fetchedEvent) return next(new AppError('Event not found', 404));

    if (fetchedEvent.submissionDeadline < new Date())
      return next(new AppError('Event submission deadline has passed', 400));

    const totalClaimAmount = zodResult.data.expensesClaims.reduce(
      (acc, claim) => acc + claim.amount,
      0
    );

    const newExpenseForm = await prisma.expensesForm.create({
      data: {
        eventId: zodResult.data.eventId,
        memberCategory: zodResult.data.memberCategory,
        userId: req.user!.id,
        totalClaimAmount,
      },
    });

    const newExpenseClaims = await prisma.expenseClaims.createMany({
      data: zodResult.data.expensesClaims.map((claim) => ({
        ...claim,
        userId: req.user!.id,
        expensesFormId: newExpenseForm.id,
      })),
    });

    res.status(201).json({
      status: 'success',
      data: {
        expenseForm: newExpenseForm,
        expenseClaims: newExpenseClaims,
      },
    });
  }
);

export const getAllExpenseFormsByUser = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const expenseForms = await prisma.expensesForm.findMany({
      where: {
        userId: req.user!.id,
      },
      include: {
        expensesClaims: true,
      },
    });

    res.status(200).json({
      status: 'success',
      data: expenseForms,
    });
  }
);

export const getAllExpenseFormsByEvent = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const eventId = req.params.eventId;

    const expenseForms = await prisma.expensesForm.findMany({
      where: {
        eventId,
      },
      include: {
        expensesClaims: true,
        user: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
    });

    res.status(200).json({
      status: 'success',
      data: expenseForms,
    });
  }
);

export const getExpenseFormById = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const expenseFormId = req.params.id;

    const expenseForm = await prisma.expensesForm.findUnique({
      where: {
        id: expenseFormId,
      },
      include: {
        expensesClaims: true,
        user: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
    });

    if (!expenseForm) return next(new AppError('Expense form not found', 404));

    if (expenseForm.userId !== req.user!.id && req.user!.role === Role.USER) {
      return next(
        new AppError('You do not have permission to view this form', 403)
      );
    }

    res.status(200).json({
      status: 'success',
      data: expenseForm,
    });
  }
);

export const validateExpenseForm = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const expenseFormId = req.params.expenseFormId;

    const fetchedExpenseForm = await prisma.expensesForm.findUnique({
      where: {
        id: expenseFormId,
      },
    });
    if (!fetchedExpenseForm)
      return next(new AppError('Expense form not found', 404));

    if (fetchedExpenseForm.sanctionStatus === SanctionStatus.APPROVED)
      return next(new AppError('Expense form already approved', 400));

    const zodResult = approveExpenseFormSchema.safeParse(req.body);

    if (!zodResult.success) {
      const errors = zodResult.error.errors.map((error) => error.message);
      return next(new AppError(errors.join(', '), 400));
    }

    const { sanctionStatus, costCenter, voucherNumber, reasonForRejection } =
      zodResult.data;

    if (sanctionStatus === 'REJECTED' && !reasonForRejection) {
      return next(new AppError('Reason for rejection is required', 400));
    }

    const updatedExpenseForm = await prisma.expensesForm.update({
      where: {
        id: expenseFormId,
      },
      data: {
        sanctionStatus,
        costCenter: sanctionStatus === 'APPROVED' ? costCenter : null,
        voucherNumber: sanctionStatus === 'APPROVED' ? voucherNumber : null,
        reasonForRejection:
          sanctionStatus === 'REJECTED' ? reasonForRejection : null,
        validatedBy: req.user!.id,
        validatedAt: new Date(),
      },
    });

    res.status(200).json({
      status: 'success',
      data: updatedExpenseForm,
    });
  }
);

export const reimburseExpenseForm = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const expenseFormId = req.params.expenseFormId;
    const zodResult = reimburseExpenseFormSchema.safeParse(req.body);

    if (!zodResult.success) {
      const errors = zodResult.error.errors.map((error) => error.message);
      return next(new AppError(errors.join(', '), 400));
    }

    const { reimbursementDate, bankReferenceNumber } = zodResult.data;
    const fetchedExpenseForm = await prisma.expensesForm.findUnique({
      where: {
        id: expenseFormId,
      },
    });
    if (!fetchedExpenseForm)
      return next(new AppError('Expense form not found', 404));

    if (fetchedExpenseForm.sanctionStatus !== SanctionStatus.APPROVED)
      return next(new AppError('Expense form not approved', 400));

    const updatedExpenseForm = await prisma.expensesForm.update({
      where: {
        id: expenseFormId,
      },
      data: {
        reimbursementDate,
        bankReferenceNumber,
        sanctionStatus: SanctionStatus.REIMBURSED,
      },
    });

    res.status(200).json({
      status: 'success',
      data: updatedExpenseForm,
    });
  }
);
