package did

import (
	"context"
	"crypto"
	"github.com/sirupsen/logrus"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
)

// ResolveKeyForDID resolves a public key from a DID for a given KID.
func ResolveKeyForDID(ctx context.Context, resolver resolution.Resolver, did, kid string) (pubKey crypto.PublicKey, err error) {
	resolved, err := resolver.Resolve(ctx, did, nil)
	if err != nil {
		err = errors.Wrapf(err, "resolving DID: %s", did)
		return nil, err
	}

	logrus.Debugln("ResolveKeyForDID kid %d", kid)

	// next, get the verification information (key) from the did document
	pubKey, err = didsdk.GetKeyFromVerificationMethod(resolved.Document, kid)
	if err != nil {
		err = errors.Wrapf(err, "getting verification information from DID Document: %s", did)
		return nil, err
	}
	return pubKey, err
}

// VerifyTokenFromDID verifies that the information in the token was digitally signed by the public key associated with
// the public key of the verification method of the did's document. The passed in resolver is used to map from the did
// to the did document.
func VerifyTokenFromDID(ctx context.Context, resolver resolution.Resolver, did, kid string, token keyaccess.JWT) error {
	logrus.Debugln("start VerifyTokenFromDID")
	resolved, err := resolver.Resolve(ctx, did)
	if err != nil {
		return errors.Wrapf(err, "resolving DID: %s", did)
	}
	logrus.Debugln("did IsEmpty %d", resolved.Document.IsEmpty())
	logrus.Debugln("len verificationMethod %d", len(resolved.Document.VerificationMethod))
	logrus.Debugln("get resolved %s", kid)

	// get the verification information from the DID document
	pubKey, err := didsdk.GetKeyFromVerificationMethod(resolved.Document, kid)
	if err != nil {
		return errors.Wrapf(err, "getting verification information from the DID document: %s", did)
	}
	logrus.Debugln("get pubKey")
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(did, kid, pubKey)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create application verifier")
	}
	logrus.Debugln("get Verify")
	if err = verifier.Verify(token); err != nil {
		return util.LoggingErrorMsg(err, "could not verify the application's signature")
	}
	return nil
}
