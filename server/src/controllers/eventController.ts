import { Request, Response, NextFunction } from 'express';

import prisma from '../utils/prisma';
import catchAsync from '../utils/catchAsync';
import {
  createEventSchema,
  updateEventSchema,
} from '../validators/eventValidators';
import AppError from '../utils/AppError';

export const createEvent = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const zodResult = createEventSchema.safeParse(req.body);

    if (!zodResult.success) {
      const errors = zodResult.error.errors.map((error) => error.message);
      return next(new AppError(errors.join(', '), 400));
    }

    const { name, location, submissionDeadline } = zodResult.data;

    const newEvent = await prisma.event.create({
      data: {
        name,
        location,
        submissionDeadline,
      },
    });

    res.status(201).json({
      status: 'success',
      data: newEvent,
    });
  }
);

export const getAllEvents = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const events = await prisma.event.findMany({
      orderBy: {
        submissionDeadline: 'desc',
      },
    });

    res.status(200).json({
      status: 'success',
      data: events,
    });
  }
);

export const getAllEligibleEvents = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const events = await prisma.event.findMany({
      where: {
        submissionDeadline: {
          gte: new Date(),
        },
      },
      orderBy: {
        submissionDeadline: 'desc',
      },
    });

    res.status(200).json({
      data: events,
    });
  }
);

export const updateEvent = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { eventId } = req.params;
    const fetchedEvent = await prisma.event.findUnique({
      where: { id: eventId },
    });

    if (!fetchedEvent) return next(new AppError('Event not found', 404));

    const zodResult = updateEventSchema.safeParse(req.body);

    if (!zodResult.success) {
      const errors = zodResult.error.errors.map((error) => error.message);
      return next(new AppError(errors.join(', '), 400));
    }

    const updatedEvent = await prisma.event.update({
      where: {
        id: eventId,
      },
      data: zodResult.data,
    });

    res.status(200).json({
      status: 'success',
      data: updatedEvent,
    });
  }
);

export const deleteEvent = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { eventId } = req.params;
    const fetchedEvent = await prisma.event.findUnique({
      where: { id: eventId },
    });

    if (!fetchedEvent) return next(new AppError('Event not found', 404));

    await prisma.event.delete({
      where: {
        id: eventId,
      },
    });

    res.status(204).json({
      status: 'success',
      data: null,
    });
  }
);
