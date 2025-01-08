"use server";

import { getUserByEmail } from "@/data/user";
import { prisma } from "@/db/prisma";
import { passwordSchema } from "@/schemas";
import { z } from "zod";
import bcrypt from "bcryptjs";

export const newPassword = async (
  values: z.infer<typeof passwordSchema>,
  token: string | null
) => {
  if (!token) return { error: "Invalid token!" };
  const validatedField = passwordSchema.safeParse(values);
  if (!validatedField.success) return { error: "Invalid password!" };

  const { password } = validatedField.data;

  const existingToken = await prisma.passwordResetToken.findUnique({
    where: { token },
  });
  if (!existingToken) return { error: "Invalid token!" };

  const hasExpired = new Date(existingToken.expires) < new Date();
  if (hasExpired) return { error: "Token has expired!" };

  const existingUser = await getUserByEmail(existingToken.email);

  if (!existingUser) return { error: "Email does not exist!" };
  // TODO Add regex password
  const hashedPassword = await bcrypt.hash(password, 10);
  await prisma.user.update({
    where: { id: existingUser.id },
    data: {
      password: hashedPassword,
    },
  });
  await prisma.passwordResetToken.delete({
    where: { id: existingToken.id },
  });
  return { success: "Password updated!" };
};
