const generateOTP = () => {
  const emailVerifyOTP = Math.floor(1000 + Math.random() * 9000);
  return { emailVerifyOTP };
};

export { generateOTP };
