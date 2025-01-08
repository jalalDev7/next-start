"use server";

import { getUserByEmail } from "@/data/user";
import { sendResetPasswordEmail } from "@/lib/mail";
import { generateResetPasswordToken } from "@/lib/tokens";
import { resetSchema } from "@/schemas";
import { z } from "zod";

export const reset = async (values: z.infer<typeof resetSchema>) => {
  const validatedFields = resetSchema.safeParse(values);
  if (!validatedFields.success) return { error: "Invalid email!" };
  const { email } = validatedFields.data;
  const user = await getUserByEmail(email);
  if (!user) return { error: "Email not found!" };

  const passwordResetToken = await generateResetPasswordToken(email);
  await sendResetPasswordEmail(
    passwordResetToken.email,
    passwordResetToken.token
  );

  return { success: "Reset email send!" };
};
