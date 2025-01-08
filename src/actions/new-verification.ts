"use server";
import { getUserByEmail } from "@/data/user";
import { getVerificationTokenByToken } from "@/data/verification-token";
import { prisma } from "@/db/prisma";

export const newVerification = async (token: string) => {
  const checkToken = await getVerificationTokenByToken(token);

  if (!checkToken) return { error: "Token does not exist!" };

  const checkExpires = new Date(checkToken.expires) < new Date();
  if (checkExpires) return { error: "Token has expired!" };

  const checkUser = await getUserByEmail(checkToken.email);

  if (!checkUser) return { error: "Email does not exist!" };
  await prisma.user.update({
    where: {
      id: checkUser.id,
    },
    data: {
      emailVerified: new Date(),
      email: checkToken.email,
    },
  });
  await prisma.verificationToken.delete({
    where: { id: checkToken.id },
  });
  return { success: "Email verified!" };
};
