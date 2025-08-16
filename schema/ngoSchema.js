const { z } = require('zod');

const ngoSchema = z.object({
  email: z.string().email(),
  phone: z.string().min(6),
  name: z.string().min(1),
  location: z.object({
    address: z.string().min(1),
    coordinates: z.object({
      lat: z.number().min(-90).max(90),
      lng: z.number().min(-180).max(180)
    })
  }),
  password: z.string().min(6),
  inventorySize: z.number().nonnegative().optional(),
  requiredClothing: z.string().optional(),
  logoUrl: z.string().url().optional(),
  bio: z.string().optional(),
  summary: z.string().optional()
});

module.exports = ngoSchema;
