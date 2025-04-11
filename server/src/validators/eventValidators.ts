import z from 'zod';

export const createEventSchema = z.object({
  name: z.string().min(1, 'Event name is required'),
  location: z.string().min(1, 'Event location is required'),
  submissionDeadline: z
    .string()
    .transform((str) => new Date(str))
    .refine((date) => !isNaN(date.getTime()), {
      message: 'Invalid date format',
    }),
});

export const updateEventSchema = z.object({
  name: z.string().min(1, 'Event name is required').optional(),
  location: z.string().min(1, 'Event location is required').optional(),
  submissionDeadline: z
    .string()
    .transform((str) => new Date(str))
    .refine((date) => !isNaN(date.getTime()), {
      message: 'Invalid date format',
    })
    .optional(),
});
