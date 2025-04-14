import {
  CostCenter,
  ExpenseClaimType,
  MemberCategory,
  SanctionStatus,
} from '@prisma/client';
import z from 'zod';

const createExpenseClaimSchema = z.object({
  date: z
    .string()
    .transform((str) => new Date(str))
    .refine((date) => !isNaN(date.getTime()), {
      message: 'Invalid date format',
    }),
  amount: z.number().min(0, 'Amount must be a positive number'),
  remarks: z.string().optional(),
  expenseClaimType: z.nativeEnum(ExpenseClaimType),
  billUrl: z.string().url('Invalid URL format'),
});

export const createExpenseFormSchema = z.object({
  eventId: z.string().nonempty('Event ID is required'),
  memberCategory: z.nativeEnum(MemberCategory),
  expensesClaims: z.array(createExpenseClaimSchema),
});

export const approveExpenseFormSchema = z.object({
  costCenter: z.nativeEnum(CostCenter),
  sanctionStatus: z.enum(['APPROVED', 'REJECTED']),
  voucherNumber: z.string().nonempty('Voucher number is required'),
  reasonForRejection: z.string().optional(),
});

export const reimburseExpenseFormSchema = z.object({
  reimbursementDate: z
    .string()
    .transform((str) => new Date(str))
    .refine((date) => !isNaN(date.getTime()), {
      message: 'Invalid date format',
    }),
  bankReferenceNumber: z.string().nonempty('Bank reference number is required'),
});
