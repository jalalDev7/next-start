import Link from "next/link";
import React from "react";
import { FaCircleUser } from "react-icons/fa6";
import FormError from "../notifications/FormError";

const ErrorCard = () => {
  return (
    <div className="flex flex-col w-full items-center justify-center h-full ">
      <FaCircleUser className="size-16" />
      <h1 className="text-lg font-semibold mb-4 mt-4">
        Ops ! Something went wrong!
      </h1>
      <FormError message="Please retry login process!" />
      <Link href="/auth/login" className="mt-8 text-sm font-semibold underline">
        Go back to login page
      </Link>
    </div>
  );
};

export default ErrorCard;
