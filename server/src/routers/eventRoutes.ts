import { Router } from 'express';
import { protect, restrictTo } from '../controllers/authController';
import {
  createEvent,
  deleteEvent,
  getAllEligibleEvents,
  getAllEvents,
  updateEvent,
} from '../controllers/eventController';

const router = Router();

router.use(protect);
router.get('/eligible', getAllEligibleEvents);
router.patch('/:eventId', restrictTo('ADMIN'), updateEvent);
router.delete('/:eventId', restrictTo('ADMIN'), deleteEvent);
router.get('/', getAllEvents);
router.post('/', restrictTo('ADMIN'), createEvent);

export default router;
