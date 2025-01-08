"use client";
import React, { useCallback, useEffect, useState } from "react";
import { FaCircleUser } from "react-icons/fa6";
import FormSuccess from "../notifications/FormSuccess";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { newVerification } from "@/actions/new-verification";
import FormError from "../notifications/FormError";
import { LuLoaderCircle } from "react-icons/lu";

export const NewVerification = () => {
  const searchParams = useSearchParams();
  const getToken = searchParams.get("token");

  const [error, setError] = useState<string | undefined>();
  const [success, setSuccess] = useState<string | undefined>();

  const onSubmit = useCallback(() => {
    if (!getToken) return setError("Missing token!");
    newVerification(getToken)
      .then((data) => {
        setSuccess(data.success);
        setError(data.error);
      })
      .catch(() => {
        setError("Something went wrong!");
      });
  }, [getToken]);
  useEffect(() => {
    onSubmit();
  }, [onSubmit]);
  return (
    <div className="flex flex-col w-full items-center justify-center h-full ">
      <FaCircleUser className="size-16" />
      <h1 className="text-lg font-semibold mb-4 mt-4">Email verification</h1>
      {error || success ? (
        <>
          <FormSuccess message={success} />
          <FormError message={error} />
        </>
      ) : (
        <LuLoaderCircle className="size-8 animate-spin" />
      )}

      <Link href="/auth/login" className="mt-8 text-sm font-semibold underline">
        Go back to login page
      </Link>
    </div>
  );
};
