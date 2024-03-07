// import { prisma } from "../../constants";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Request, Response } from "express";

interface IRegister {
  email: string;
  accepts_marketing: boolean;
  first_name: string;
  last_name: string;
  state: string;
  phone: string;
  addresses: [] | any;
  password: string;
}

const prisma = new PrismaClient();

//utils
export async function hashPassword(password: string) {
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

export async function register(req: Request, res: Response) {
  try {
    const {
      first_name,
      last_name,
      phone,
      password,
    }: IRegister = req.body;
    if (
      !password ||
      !first_name ||
      !last_name ||
      !phone ||
    ) {
      console.error("Missing fields");
    }
    const validateEmail = await prisma.customers.findUnique({
      where: {
        phone: phone,
      } as any,
    });
    if (validateEmail) {
      console.error(
        "Request failed, registration may only specify unknown emails",
      );
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await prisma.customers.create({
      data: {
        first_name,
        last_name,
        phone,
        password: hashedPassword,
      } as any,
    });

    if (user) {
      res.status(200).json({
        message: "User created successfully",
        user: [user],
        token: jwt.sign({ id: user.id }, process.env.JWT_SECRET as string, {
          expiresIn: "30d",
        }),
      });
    } else {
      res.status(500).json({
        message: "Something went wrong",
      });
    }
  } catch (error) { }
}


export async function login(req: Request, res: Response) {
  const email = req.body.email as string;
  const password = req.body.password as string;

  if (!email) {
    res.status(400).json({ error: 'Missing email' });
    return;
  }

  if (!password) {
    res.status(400).json({ error: 'Missing password' });
    return;
  }


  try {
    const users = await prisma.customers.findMany({
      where: { email: email }
    })

    /**
     * NOTE:
     * Concerned for when there are more than one users in the database.
     * @Assumption
     * Only One user Record is there.
     */
    if (users.length === 0) {
      res.status(404).json({ error: 'No user found' });
      return;
    }

    const user = users[0];
    const user_password = user.password === null || user.password === undefined ? '' : user.password;
    const validPassword = await bcrypt.compare(password, user_password);
    if (!validPassword) {
      res.status(403).json({ error: "Unauthenticated" });
      console.error("Invalid credentials");
      return
    }

    res.status(200).json({
      message: "User logged in successfully",
      user: [user],
      token: jwt.sign({ id: user.id }, process.env.JWT_SECRET as string, {
        expiresIn: "30d",
      }),
    });
  } catch (error) {
    res.sendStatus(500);
    console.error(error);
  }
}