"use client";
import FacebookSVG from "@/components/SVGs/FacebookSVG";
import GoogleSVG from "@/components/SVGs/GoogleSVG";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import React, { useState, useTransition } from "react";
import { FaCircleUser } from "react-icons/fa6";
import * as z from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import Link from "next/link";
import FormError from "@/components/notifications/FormError";
import FormSuccess from "@/components/notifications/FormSuccess";
import { loginSchema } from "@/schemas";
import { login } from "@/actions/login";

const Login = () => {
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | undefined>();
  const [success, setSuccess] = useState<string | undefined>();
  const form = useForm<z.infer<typeof loginSchema>>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      username: "",
      password: "",
    },
  });
  const onSubmit = (values: z.infer<typeof loginSchema>) => {
    setError("");
    setSuccess("");
    startTransition(() => {
      login(values).then((data) => {
        setError(data.error);
        setSuccess(data.success);
      });
    });
  };
  return (
    <div className="flex flex-col w-full items-center justify-center h-full ">
      <FaCircleUser className="size-16" />
      <h1 className="text-lg font-semibold mb-8 mt-4">
        Welcome to sign in page
      </h1>
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="w-full">
          <div className="flex flex-col w-full items-start justify-start gap-2">
            <FormField
              control={form.control}
              name="username"
              render={({ field }) => (
                <FormItem className="w-full">
                  <FormLabel className="font-semibold">
                    Username or email :
                  </FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      disabled={isPending}
                      type="text"
                      placeholder="Username or email"
                      className="w-full"
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

            <Button disabled={isPending} type="submit" className="w-full mt-2">
              Sign in
            </Button>
            <FormError message={error} />
            <FormSuccess message={success} />
          </div>
        </form>
      </Form>
      <div className="flex flex-col gap-2 mt-4 w-full">
        <div className="flex flex-row gap-2 items-center justify-center border border-primary rounded-lg p-2 w-full cursor-pointer">
          <GoogleSVG className="size-6" />
          <h2>Sign in with google</h2>
        </div>
        <div className="flex flex-row gap-2 items-center justify-center border border-primary rounded-lg p-2 w-full cursor-pointer">
          <FacebookSVG className="size-6" />
          <h2>Sign in with facebook</h2>
        </div>
        <Link
          href="/auth/register"
          className="flex items-center mt-4 text-sm font-semibold text justify-center w-full underline"
        >
          Don{"'"}t have an account ?
        </Link>
      </div>
    </div>
  );
};

export default Login;