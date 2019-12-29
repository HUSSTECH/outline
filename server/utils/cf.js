import AWS from 'aws-sdk';

const AWS_CLOUDFRONT_KEY_PAIR_ID = process.env.AWS_CLOUDFRONT_KEY_PAIR_ID;
const AWS_CLOUDFRONT_PRIVATE_KEY = process.env.AWS_CLOUDFRONT_PRIVATE_KEY;
const AWS_CLOUDFRONT_URL = process.env.AWS_CLOUDFRONT_URL;
const AWS_S3_UPLOAD_BUCKET_NAME = process.env.AWS_S3_UPLOAD_BUCKET_NAME;
const AWS_S3_UPLOAD_BUCKET_URL = process.env.AWS_S3_UPLOAD_BUCKET_URL;

const policy = JSON.stringify({
  Statement: [
    {
      Resource: `${process.env.AWS_CLOUDFRONT_URL}/*`,
      Condition: {
        DateLessThan: {
          'AWS:EpochTime':
            Math.floor(new Date().getTime() / 1000) + 60 * 60 * 1, // Current Time in UTC + time in seconds, (60 * 60 * 1 = 1 hour)
        },
      },
    },
  ],
});

export async function getSignedCloudFrontCookie() {
    const cloudFront = new AWS.CloudFront.Signer(
      AWS_CLOUDFRONT_KEY_PAIR_ID,
      AWS_CLOUDFRONT_PRIVATE_KEY
    );
    const cookie = cloudFront.getSignedCookie({
        policy,
    });
  return cookie;
};

const urlReplacer = text => {
    return text.replace(`${AWS_S3_UPLOAD_BUCKET_URL}/${AWS_S3_UPLOAD_BUCKET_NAME}`, AWS_CLOUDFRONT_URL);
}

export const CFUrlReplacer = AWS_CLOUDFRONT_URL && urlReplacer;

export const getCfCookieDomain = hostname => {
    // can only have 1 level deep subdomains on CF anyway
    return (hostname === 'localhost' ? hostname : `.${hostname.split('.').slice(-2).join('.')}`);
}