import { SetMetadata } from '@nestjs/common';

// Bypass ATGuard

export const PublicRoute = () => SetMetadata('isPublic', true);
