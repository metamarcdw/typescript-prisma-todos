import { prisma } from '../generated/prisma-client';

async function main(): Promise<void> {
  await prisma.deleteManyTodoes({ id_not: 0 });
  console.log('Deleted all Todos.');

  await prisma.deleteManyUsers({ id_not: 0 });
  console.log('Deleted all Users.');
}

main().catch((err: Error): void => console.error(err));
