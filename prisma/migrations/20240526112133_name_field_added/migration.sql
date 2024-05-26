/*
  Warnings:

  - You are about to drop the column `userId` on the `OTP` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[mobile]` on the table `OTP` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `mobile` to the `OTP` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "OTP" DROP CONSTRAINT "OTP_userId_fkey";

-- DropIndex
DROP INDEX "OTP_userId_key";

-- DropIndex
DROP INDEX "userId_idx";

-- AlterTable
ALTER TABLE "OTP" DROP COLUMN "userId",
ADD COLUMN     "mobile" TEXT NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "OTP_mobile_key" ON "OTP"("mobile");

-- CreateIndex
CREATE INDEX "user_mobile_idx" ON "OTP"("mobile");

-- AddForeignKey
ALTER TABLE "OTP" ADD CONSTRAINT "OTP_mobile_fkey" FOREIGN KEY ("mobile") REFERENCES "users"("mobile") ON DELETE RESTRICT ON UPDATE CASCADE;
