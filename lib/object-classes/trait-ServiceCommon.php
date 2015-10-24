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

trait ServiceCommon
{
    use ReferencableObject {removeReference as super_removeReference;}

    public function isService()
    {
        return false;
    }

    public function isGroup()
    {
        return false;
    }

    public function isTmpSrv()
    {
        return false;
    }

    public function removeReference($ref)
    {
        $this->super_removeReference($ref);
    }

    /**
     * @param $objectToAdd Service|ServiceGroup
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
            if( $refClass == 'ServiceGroup' )
            {
                /** @var $ref ServiceGroup */
                if( $displayOutput )
                    print $outputPadding."- adding in {$ref->_PANC_shortName()}\n";
                $ref->add($objectToAdd);
            }
            elseif( $refClass == 'ServiceRuleContainer' )
            {
                /** @var $ref ServiceRuleContainer */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' )
                {
                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->add($objectToAdd);
                }
                elseif( $ruleClass == 'NatRule' )
                {
                    derr('unsupported use case in '.$ref->_PANC_shortName());
                }
                else
                    derr('unsupported owner_class: '.$ruleClass);
            }
            else
                derr('unsupport class : '.$refClass);
        }
    }

    /**
     * @param $objectToAdd Service|ServiceGroup
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
            if( $refClass == 'ServiceGroup' )
            {
                /** @var $ref ServiceGroup */
                if( $displayOutput )
                    print $outputPadding."- adding in {$ref->_PANC_shortName()}\n";
                $ref->API_add($objectToAdd);
            }
            elseif( $refClass == 'ServiceRuleContainer' )
            {
                /** @var $ref ServiceRuleContainer */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' )
                {
                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->API_add($objectToAdd);
                }
                elseif( $ruleClass == 'NatRule' )
                {
                    derr('unsupported use case in '.$ref->_PANC_shortName());
                }
                else
                    derr('unsupported owner_class: '.$ruleClass);
            }
            else
                derr('unsupport class : '.$refClass);
        }
    }

}