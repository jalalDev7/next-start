import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().min(3, "Email is required"),
  password: z.string().min(6, "Password is required"),
});

export const registerSchema = z.object({
  name: z.string().min(3, "Please enter your name"),
  email: z.string().email("Invalid email"),
  password: z.string().min(6, "Minimum of 6 characters required!"),
  rePassword: z
    .string()
    .min(6, "Please make sure both passwords are the same."),
});

export const resetSchema = z.object({
  email: z.string().min(3, "Email is required"),
});

export const passwordSchema = z.object({
  password: z.string().min(6, "Minimum of 6 characters required!"),
});
