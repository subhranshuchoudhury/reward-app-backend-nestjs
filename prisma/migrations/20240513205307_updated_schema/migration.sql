/*
  Warnings:

  - You are about to drop the column `mobile` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `name` on the `users` table. All the data in the column will be lost.
  - You are about to drop the `Otp` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "Otp" DROP CONSTRAINT "Otp_userid_fkey";

-- DropIndex
DROP INDEX "users_mobile_key";

-- AlterTable
ALTER TABLE "users" DROP COLUMN "mobile",
DROP COLUMN "name";

-- DropTable
DROP TABLE "Otp";

-- CreateTable
CREATE TABLE "UsedHashes" (
    "id" SERIAL NOT NULL,
    "hash" TEXT NOT NULL,
    "userId" TEXT,

    CONSTRAINT "UsedHashes_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "UsedHashes" ADD CONSTRAINT "UsedHashes_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
