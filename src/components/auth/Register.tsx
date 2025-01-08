"use client";
import { register } from "@/actions/register";
import FacebookSVG from "@/components/SVGs/FacebookSVG";
import GoogleSVG from "@/components/SVGs/GoogleSVG";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { registerSchema } from "@/schemas";
import { zodResolver } from "@hookform/resolvers/zod";
import React, { useState, useTransition } from "react";
import { useForm } from "react-hook-form";
import { FaCircleUser } from "react-icons/fa6";
import { z } from "zod";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "../ui/form";
import Link from "next/link";
import FormError from "../notifications/FormError";
import FormSuccess from "../notifications/FormSuccess";
import { signIn } from "next-auth/react";
import { DEFAULT_LOGIN_REDIRECT } from "@/routes";

const Register = () => {
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | undefined>();
  const [success, setSuccess] = useState<string | undefined>();
  const form = useForm<z.infer<typeof registerSchema>>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      email: "",
      name: "",
      password: "",
      rePassword: "",
    },
  });
  const onSubmit = (values: z.infer<typeof registerSchema>) => {
    setError("");
    setSuccess("");
    startTransition(() => {
      register(values).then((data) => {
        setError(data.error);
        setSuccess(data.success);
      });
    });
  };
  const providerClick = (provider: string) => {
    signIn(provider, { callbackUrl: DEFAULT_LOGIN_REDIRECT });
  };
  return (
    <div className="flex flex-col w-full items-center justify-center h-full ">
      <FaCircleUser className="size-16" />
      <h1 className="text-lg font-semibold mb-8 mt-4">
        Welcome to register page
      </h1>
      <Form {...form}>
        <form className="w-full" onSubmit={form.handleSubmit(onSubmit)}>
          <div className="flex flex-col w-full items-start justify-start gap-2">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem className="w-full">
                  <FormLabel className="font-semibold">Name :</FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      disabled={isPending}
                      type="text"
                      placeholder="John smith"
                      className=""
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem className="w-full">
                  <FormLabel className="font-semibold">Email :</FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      disabled={isPending}
                      type="email"
                      placeholder="email@company.com"
                      className=""
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="password"
              render={({ field }) => (
                <FormItem className="w-full">
                  <FormLabel className="font-semibold">Password :</FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      disabled={isPending}
                      type="password"
                      placeholder="Paswword"
                      className=""
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="rePassword"
              render={({ field }) => (
                <FormItem className="w-full">
                  <FormLabel className="font-semibold">
                    Confirm password :
                  </FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      disabled={isPending}
                      type="password"
                      placeholder="Paswword"
                      className=""
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button disabled={isPending} type="submit" className="w-full mt-2">
              Create account
            </Button>
            <FormError message={error} />
            <FormSuccess message={success} />
          </div>
        </form>
      </Form>

      <div className="flex flex-col gap-2 mt-4 w-full">
        <button
          className="flex flex-row gap-2 items-center justify-center border border-primary rounded-lg p-2 w-full cursor-pointer"
          onClick={() => providerClick("google")}
        >
          <GoogleSVG className="size-6" />
          <h2>Register with google</h2>
        </button>
        <button
          className="flex flex-row gap-2 items-center justify-center border border-primary rounded-lg p-2 w-full cursor-pointer"
          onClick={() => providerClick("facebook")}
        >
          <FacebookSVG className="size-6" />
          <h2>Register with facebook</h2>
        </button>
        <Link
          href="/auth/login"
          className="flex items-center mt-4 text-sm font-semibold text justify-center w-full underline"
        >
          Already have an account ?
        </Link>
      </div>
    </div>
  );
};

export default Register;
