"use server";

import { getUserByEmail } from "@/data/user";
import { prisma } from "@/db/prisma";
import { sendVerificationEmail } from "@/lib/mail";
import { generateVerificationToken } from "@/lib/tokens";
import { registerSchema } from "@/schemas";
import bcrypt from "bcryptjs";
import { z } from "zod";

export const register = async (values: z.infer<typeof registerSchema>) => {
  const validatedFields = registerSchema.safeParse(values);
  if (!validatedFields.success) {
    return { error: "Invalid fields!" };
  }
  const { name, email, password, rePassword } = validatedFields.data;

  if (password !== rePassword) {
    return { error: "Please make sure both passwords are the same." };
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const checkEmail = await getUserByEmail(email);
  if (checkEmail) {
    return { error: "Email already existe" };
  }
  await prisma.user.create({
    data: {
      name: name,
      email: email,
      password: hashedPassword,
    },
  });

  const verificationToken = await generateVerificationToken(email);
  await sendVerificationEmail(verificationToken.email, verificationToken.token);
  return { success: "Confirmation email sent!" };
};
