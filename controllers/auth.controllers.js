import { AuthService } from '../services/auth.service';

export class AuthController {
  authService = new this.authService();

  // 회원가입
  signUp = async (req, res, next) => {
    try {
      const { email, password, passwordConfirm, name } = req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          message: '이메일 입력이 필요합니다.',
        });
      }

      if (!password) {
        return res.status(400).json({
          success: false,
          message: '비밀번호 입력이 필요합니다.',
        });
      }

      if (!passwordConfirm) {
        return res.status(400).json({
          success: false,
          message: '비밀번호 확인 입력이 필요합니다.',
        });
      }

      if (!name) {
        return res.status(400).json({
          success: false,
          message: '이름 입력이 필요합니다.',
        });
      }

      if (password !== passwordConfirm) {
        return res.status(400).json({
          success: false,
          message: '입력 한 비밀번호가 서로 일치하지 않습니다.',
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: '비밀번호는 최소 6자리 이상입니다.',
        });
      }

      let emailValidationRegex = new RegExp('[a-z0-9._]+@[a-z]+.[a-z]{2,3}');
      const isValidEmail = emailValidationRegex.test(email);
      if (!isValidEmail) {
        return res.status(400).json({
          success: false,
          message: '올바른 이메일 형식이 아닙니다.',
        });
      }

      const existedUser = await prisma.users.findfirst({ where: { email } });
      if (existedUser) {
        return res.status(400).json({
          success: false,
          message: '이미 가입 된 이메일입니다.',
        });
      }

      const hashedPassword = bcrypt.hashSync(
        password,
        PASSWORD_HASH_SALT_ROUNDS,
      );

      const [user] = await prisma.$transaction(
        async (tx) => {
          //Users 테이블에 사용자 생성
          const user = await tx.users.create({
            data: {
              email,
              name,
              password: hashedPassword,
            },
          });

          return [user];
        },
        {
          isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted,
        },
      );

      return res.status(201).json({
        success: true,
        message: '회원가입에 성공했습니다.',
        data: { email: user.email, name: user.name },
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        success: false,
        message: '예상치 못한 에러가 발생하였습니다. 관리자에게 문의하세요.',
      });
    }
  };

  // 로그인
  logIn = async (req, res, next) => {
    try {
      const { email, password } = req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          message: '이메일 입력이 필요합니다.',
        });
      }

      if (!password) {
        return res.status(400).json({
          success: false,
          message: '비밀번호 입력이 필요합니다.',
        });
      }

      const user = await prisma.users.findfirst({ where: { email } });
      const hashedPassword = user?.password ?? '';
      const isPasswordMatched = bcrypt.compareSync(password, hashedPassword);

      const isCorrectUser = user && isPasswordMatched;

      if (!isCorrectUser) {
        return res.status(401).json({
          success: false,
          message: '일치하는 인증 정보가 없습니다.',
        });
      }

      const accessToken = jwt.sign(
        { userId: user.id },
        JWT_ACCESS_TOKEN_SECRET,
        {
          expiresIn: JWT_ACCESS_TOKEN_EXPIRES_IN,
        },
      );

      return res.status(200).json({
        success: true,
        message: '로그인에 성공했습니다.',
        data: { accessToken },
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        success: false,
        message: '예상치 못한 에러가 발생하였습니다. 관리자에게 문의하세요.',
      });
    }
  };
}
