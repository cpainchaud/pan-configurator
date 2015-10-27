<?php
/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud <cpainchaud _AT_ paloaltonetworks.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

trait AddressCommon
{
    use ReferencableObject {removeReference as super_removeReference;}

    public function isAddress()
    {
        return false;
    }

    public function isGroup()
    {
        return false;
    }

    public function isTmpAddr()
    {
        return false;
    }

    public function removeReference($ref)
    {
        $this->super_removeReference($ref);
    }

    /**
     * @param $objectToAdd Address|AddressGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false)
    {
        if( $skipIfConflict )
            derr('unsupported');

        if( !is_string($outputPadding) )
            $outputPadding = str_pad('', $outputPadding);

        foreach($this->refrules as $ref)
        {
            $refClass = get_class($ref);
            if( $refClass == 'AddressGroup' )
            {
                /** @var $ref AddressGroup */
                if( $displayOutput )
                    print $outputPadding."- adding in {$ref->_PANC_shortName()}\n";
                $ref->add($objectToAdd);
            }
            elseif( $refClass == 'AddressRuleContainer' )
            {
                /** @var $ref AddressRuleContainer */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' )
                {
                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->addObject($objectToAdd);
                }
                elseif( $ruleClass == 'NatRule' )
                {
                    if( $ref->name == 'snathosts' )
                        derr('unsupported use case in '.$ref->owner->_PANC_shortName());
                    if( $ref->name == 'source' && $ref->owner->natType() == 'static-ip'  )
                        derr('unsupported use case with static-ip NAT and source insertion in '.$ref->owner->_PANC_shortName());

                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->addObject($objectToAdd);
                }
                else
                    derr('unsupported owner_class: '.$ruleClass);
            }
            else
                derr('unsupport class : '.$refClass);
        }
    }

    /**
     * @param $objectToAdd Address|AddressGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function API_addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false)
    {
        if( $skipIfConflict )
            derr('unsupported');

        if( !is_string($outputPadding) )
            $outputPadding = str_pad('', $outputPadding);

        foreach($this->refrules as $ref)
        {
            $refClass = get_class($ref);
            if( $refClass == 'AddressGroup' )
            {
                /** @var $ref AddressGroup */
                if( $displayOutput )
                    print $outputPadding."- adding in {$ref->_PANC_shortName()}\n";
                $ref->API_add($objectToAdd);
            }
            elseif( $refClass == 'AddressRuleContainer' )
            {
                /** @var $ref AddressRuleContainer */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' )
                {
                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->API_add($objectToAdd);
                }
                elseif( $ruleClass == 'NatRule' )
                {
                    if( $ref->name == 'snathosts' )
                        derr('unsupported use case in '.$ref->owner->_PANC_shortName());
                    if( $ref->name == 'source' && $ref->owner->natType() == 'static-ip'  )
                        derr('unsupported use case with static-ip NAT and source insertion in '.$ref->owner->_PANC_shortName());

                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->API_add($objectToAdd);
                }
                else
                    derr('unsupported owner_class: '.$ruleClass);
            }
            else
                derr('unsupport class : '.$refClass);
        }
    }

}