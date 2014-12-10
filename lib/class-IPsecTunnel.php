<?php


class IPsecTunnel
{
    use ReferencableObject;
    use PathableName;

    /**
     * @var null|string[]|DOMElement
     */
    public $xmlroot = null;


    /**
     * @var null|string[]|DOMElement
     */
    public $typeRoot = null;
    /**
     * @var null|string[]|DOMElement
     */
    public $proxyIdRoot = null;

    public $type = 'notfound';

    public $proxys = Array();


    public function IPsecTunnel($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    public function load_from_xml( &$xml )
    {
        derr('unsupported');
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml( $xml )
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("tunnel name not found\n");

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            if( $node->nodeName == 'auto-key' )
            {
                $this->type = 'auto-key';
                $this->typeRoot = $node;
                //print "found type auto key\n";

                // now extracts ProxyID
                $this->proxyIdRoot = DH::findFirstElementOrCreate('proxy-id', $node);

                foreach( $this->proxyIdRoot->childNodes as $proxyNode )
                {
                    if( $proxyNode->nodeType != 1 )
                        continue;


                    $local = DH::findFirstElementOrDie('local', $proxyNode);
                    $remote = DH::findFirstElementOrDie('remote', $proxyNode);

                    $record = Array('local' => $local->nodeValue, 'remote' => $remote->nodeValue, 'xmlroot' => $proxyNode );

                    $this->proxys[] = &$record;
                    unset($record);
                }
            }

        }
    }


}