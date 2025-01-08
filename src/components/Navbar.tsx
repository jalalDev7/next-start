import Link from "next/link";
import { auth, signOut } from "@/auth";
import { IoHome } from "react-icons/io5";
import { MdSpaceDashboard } from "react-icons/md";
import { ImUserPlus } from "react-icons/im";
import { RiLoginCircleFill, RiLogoutCircleFill } from "react-icons/ri";

const Navbar = async () => {
  const session = await auth();
  return (
    <nav className="flex flex-row items-center justify-center  p-2">
      <div className="flex flex-row items-center bg-primary rounded-full text-secondary w-fit gap-4 py-2 px-6">
        <Link href="/" className="flex items-center flex-row gap-1">
          <IoHome className="size-4" />
          Home
        </Link>
        <Link href="/dashboard" className="flex items-center flex-row gap-1">
          <MdSpaceDashboard className="size-4" />
          Dashboard
        </Link>
        {session && session.user ? (
          <form
            action={async () => {
              "use server";
              await signOut();
            }}
          >
            <button className="flex items-center flex-row gap-1" type="submit">
              <RiLogoutCircleFill className="size-4" />
              Sign out
            </button>
          </form>
        ) : (
          <>
            <Link
              href="/auth/register"
              className="flex items-center flex-row gap-1"
            >
              <ImUserPlus className="size-4" />
              Register
            </Link>
            <Link
              href="/auth/login"
              className="flex items-center flex-row gap-1"
            >
              <RiLoginCircleFill />
              Sign in
            </Link>
          </>
        )}
      </div>
    </nav>
  );
};

export default Navbar;
