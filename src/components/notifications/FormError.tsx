import { IoWarningOutline } from "react-icons/io5";

const FormError = ({ message }: { message?: string }) => {
  if (!message) return null;
  return (
    <div className="flex flex-row gap-2 items-center w-full my-2 bg-destructive/15 p-3 border border-destructive rounded-md text-sm text-destructive">
      <IoWarningOutline className="size-4" />
      {message}
    </div>
  );
};

export default FormError;
