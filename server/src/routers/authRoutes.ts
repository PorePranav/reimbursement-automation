import { Router } from 'express';
import {
  forgotPassword,
  login,
  protect,
  resetPassword,
  signup,
  changePassword,
  verifyUser,
  restrictTo,
  createOperatorUser,
  createAdminUser,
  isLoggedIn,
  logout,
} from '../controllers/authController';

const router = Router();

router.post('/signup', signup);
router.post('/login', login);
router.patch('/verifyUser', verifyUser);
router.post('/forgotPassword', forgotPassword);
router.patch('/resetPassword', resetPassword);
router.post('/signupAdmin', createAdminUser);
router.get('/isLoggedIn', isLoggedIn);
router.get('/logout', logout);

router.use(protect);
router.patch('/changePassword', changePassword);
router.post('/signupOperator', restrictTo('ADMIN'), createOperatorUser);

export default router;
