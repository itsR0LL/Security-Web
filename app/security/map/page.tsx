import { redirect } from "next/navigation";

export default function SecurityMapPage() {
  redirect("/security/situation?view=2d");
}
