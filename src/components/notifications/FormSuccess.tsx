import { MdOutlineFileDownloadDone } from "react-icons/md";

const FormSuccess = ({ message }: { message?: string }) => {
  if (!message) return null;
  return (
    <div className="flex flex-row gap-2 items-center w-full my-2 bg-emerald-500/15 p-3 border border-emerald-500 rounded-md text-sm text-emerald-500">
      <MdOutlineFileDownloadDone className="size-4" />
      {message}
    </div>
  );
};

export default FormSuccess;
