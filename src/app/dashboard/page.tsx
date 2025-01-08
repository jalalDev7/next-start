import React from "react";
import { auth } from "@/auth";
import Navbar from "@/components/Navbar";
import Image from "next/image";

const page = async () => {
  const user = await auth();
  return (
    <div className="flex flex-col w-full items-center justify-center">
      <Navbar />
      <div className="text-lg font-semibold flex flex-col gap-2 items-center justify-center bg-primary text-secondary rounded-xl p-4 w-fit">
        <div className="flex w-full rounded-lg bg-secondary text-primary px-4 py-2 items-center justify-between gap-8">
          <h1>Name :</h1> {user?.user?.name}
        </div>
        <div className="flex w-full rounded-lg bg-secondary text-primary px-4 py-2 items-center justify-between gap-8">
          <h1>Email :</h1> {user?.user?.email}
        </div>
        <div className="flex w-full rounded-lg bg-secondary text-primary px-4 py-2 items-center justify-between gap-8">
          <h1>Id :</h1> {user?.user?.id}
        </div>
        <div className="flex w-full rounded-lg bg-secondary text-primary px-4 py-2 items-center justify-between gap-8">
          <h1>Role :</h1> {user?.user?.role}
        </div>
        <div className="flex w-full rounded-lg bg-secondary text-primary px-4 py-2 items-center justify-between gap-8">
          <h1>isOAuth :</h1> {user?.user.isOauth ? "true" : "false"}
        </div>
        <div className="flex w-full rounded-lg bg-secondary text-primary px-4 py-2 items-center justify-between gap-8">
          Image :
          {user && user.user.image ? (
            <Image
              src={user?.user.image}
              width={30}
              height={30}
              className="rounded-full"
              alt="avatar"
            />
          ) : (
            "No image"
          )}
        </div>
      </div>
    </div>
  );
};

export default page;
