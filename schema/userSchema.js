const { z } = require('zod');

const userSchema = z.object({
  email: z.string().email(),
  phone: z.string().min(6),
  name: z.string().min(1),
  location: z.string().optional(),
  avatarUrl: z.string().url().optional(),
  bio: z.string().optional(),
  password: z.string().min(6)
});

module.exports = userSchema;
