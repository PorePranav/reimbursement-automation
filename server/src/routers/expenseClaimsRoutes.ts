import { Router } from 'express';
import { protect, restrictTo } from '../controllers/authController';
import {
  createExpenseForm,
  getAllExpenseFormsByEvent,
  getAllExpenseFormsByUser,
  getExpenseFormById,
  protectExpense,
  reimburseExpenseForm,
  validateExpenseForm,
} from '../controllers/expensesClaimsController';

const router = Router();

router.use(protect, protectExpense);
router.get('/:id', getExpenseFormById);
router.post('/', createExpenseForm);
router.get('/', getAllExpenseFormsByUser);

router.use(restrictTo('ADMIN', 'OPERATOR'));
router.get('/event/:eventId', getAllExpenseFormsByEvent);
router.get('/user/:userId', getAllExpenseFormsByEvent);
router.patch('/validate/:expenseFormId', validateExpenseForm);
router.patch('/reimburse/:expenseFormId', reimburseExpenseForm);

export default router;
