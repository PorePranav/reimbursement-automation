import dotenv from 'dotenv';
dotenv.config();

import app from './app';

process.on('uncaughtException', (err: Error) => {
  console.log('Uncaught Exception, Shutting Down');
  console.error(err);
  process.exit(1);
});

const port = process.env.PORT || 3000;

if (process.env.NODE_ENV !== 'production') {
  const server = app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
  });

  process.on('unhandledRejection', (err: Error) => {
    console.log('Unhandled Rejection, Shutting Down');
    console.log(err);
    server.close(() => {
      process.exit(1);
    });
  });
}

export default app;
