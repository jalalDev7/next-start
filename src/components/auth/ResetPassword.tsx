"use client";
import React, { useState, useTransition } from "react";
import { FaCircleUser } from "react-icons/fa6";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "../ui/form";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import FormError from "../notifications/FormError";
import FormSuccess from "../notifications/FormSuccess";
import { resetSchema } from "@/schemas";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { reset } from "@/actions/reset";
import Link from "next/link";

export const ResetPassword = () => {
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | undefined>();
  const [success, setSuccess] = useState<string | undefined>();
  const form = useForm<z.infer<typeof resetSchema>>({
    resolver: zodResolver(resetSchema),
    defaultValues: {
      email: "",
    },
  });
  const onSubmit = (values: z.infer<typeof resetSchema>) => {
    setError("");
    setSuccess("");
    startTransition(() => {
      reset(values).then((data) => {
        setSuccess(data.success);
        setError(data.error);
      });
    });
  };
  return (
    <div className="flex flex-col w-full items-center justify-center h-full ">
      <FaCircleUser className="size-16" />
      <h1 className="text-lg font-semibold mb-8 mt-4">Forgot your pasword ?</h1>
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="w-full">
          <div className="flex flex-col w-full items-start justify-start gap-2">
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
                      type="text"
                      placeholder="email@company.com"
                      className="w-full"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <Button disabled={isPending} type="submit" className="w-full mt-2">
              Send reset email
            </Button>
            <FormError message={error} />
            <FormSuccess message={success} />
          </div>
        </form>
      </Form>
      <div className="flex flex-col gap-2 mt-4 w-full">
        <Link
          href="/auth/login"
          className="flex items-center mt-4 text-sm font-semibold text justify-center w-full underline"
        >
          Back to login page
        </Link>
      </div>
    </div>
  );
};
