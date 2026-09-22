import hashlib
import io
import unittest
from merkle_reference import compute, encode, manifest_for_cc, merkle_root
from model_weights import MANIFEST_SCHEMA, SCOPE


class MerkleReferenceTests(unittest.TestCase):
    def setUp(self):
        self.data={'a.safetensors': b'aaa', 'b.safetensors': b'bbbb', 'c.safetensors': b'ccccc'}
        self.hf={'schema':MANIFEST_SCHEMA,'scope':SCOPE,'model_id':'test/model','revision':'ab'*20,
            'files':[{'path':n,'size':len(v),'hf_digest_algorithm':'sha256','hf_digest':hashlib.sha256(v).hexdigest()} for n,v in self.data.items()]}
    def opener(self,url):return io.BytesIO(self.data[url.rsplit('/',1)[1]])
    def test_raw_merkle_nonce_and_order_parallel(self):
        nonce='01'*32
        result=compute(self.hf,nonce,workers=3,opener=self.opener)
        leaves=[hashlib.sha256(b'\0'+bytes.fromhex(nonce)+v).digest() for v in self.data.values()]
        left=hashlib.sha256(b'\1'+leaves[0]+leaves[1]).digest()
        expected=hashlib.sha256(b'\1'+left+leaves[2]).hexdigest()
        self.assertEqual(expected,result['root'])
        self.assertEqual(result,compute(self.hf,nonce,workers=1,opener=self.opener))
        self.assertNotEqual(result['root'],compute(self.hf,'02'*32,opener=self.opener)['root'])
        self.assertNotEqual(leaves[0],hashlib.sha256(b'\0'+bytes.fromhex(nonce)+hashlib.sha256(b'aaa').digest()).digest())
    def test_stream_corruption_rejected(self):
        self.data['a.safetensors']=b'xxx'
        with self.assertRaisesRegex(ValueError,'HF digest'):compute(self.hf,'01'*32,opener=self.opener)
    def test_metadata_cannot_downgrade_reference(self):
        self.hf['files'][0]['hf_digest_algorithm']='git-sha1';self.hf['files'][0]['hf_digest']='00'*20
        with self.assertRaisesRegex(ValueError,'raw SHA256'):manifest_for_cc(self.hf)
    def test_cc_e1_public_encoding_vector(self):
        self.assertEqual(encode([b'a','b']).hex(),'43432d4531006c00000002620000000161730000000162')
        self.assertEqual(encode({'z':1,'a':False}),encode({'a':False,'z':1}))
        self.assertNotEqual(encode(['ab','c']),encode(['a','bc']))
        with self.assertRaises(ValueError):encode(0.5)
        with self.assertRaises(ValueError):merkle_root([])


if __name__=='__main__':unittest.main()
