import z from 'zod';

export const signupSchema = z.object({
  name: z.string().min(2, 'Name is required').max(50, 'Name is too long'),
  email: z.string().trim().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters long'),
  confirmPassword: z.string(),
  phone: z.string().regex(/^\d{10}$/, 'Phone number must be 10 digits long'),
  userCategory: z.enum(['INDIVIDUAL', 'VENDOR']),
});

export const loginSchema = z.object({
  email: z.string().trim().email('Invalid email address'),
  password: z.string(),
});
