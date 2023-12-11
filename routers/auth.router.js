import { Router } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { prisma } from '../utils/prisma/index.js';
import { Prisma } from '@prisma/client';
import {
  PASSWORD_HASH_SALT_ROUNDS,
  JWT_ACCESS_TOKEN_SECRET,
  JWT_ACCESS_TOKEN_EXPIRES_IN,
} from '../constants/security.costant.js';
import { AuthController } from '../controllers/auth.controllers.js';

const authRouter = Router();
const authController = new AuthController();

// 회원가입
authRouter.post('/signup', authController.signUp);

// 로그인
authRouter.post('/signin', authController.logIn);

export { authRouter };
