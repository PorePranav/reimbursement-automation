import { Router } from 'express';
import { login, signup, verifyUser } from '../controllers/authController';

const router = Router();

router.post('/signup', signup);
router.post('/login', login);
router.patch('/verifyUser', verifyUser);

export default router;
