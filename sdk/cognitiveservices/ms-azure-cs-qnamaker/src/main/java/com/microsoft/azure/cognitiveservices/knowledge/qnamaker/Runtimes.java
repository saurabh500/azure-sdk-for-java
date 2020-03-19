/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 */

package com.microsoft.azure.cognitiveservices.knowledge.qnamaker;

import com.microsoft.azure.cognitiveservices.knowledge.qnamaker.models.TrainOptionalParameter;
import com.microsoft.azure.cognitiveservices.knowledge.qnamaker.models.ErrorResponseException;
import com.microsoft.azure.cognitiveservices.knowledge.qnamaker.models.FeedbackRecordDTO;
import com.microsoft.azure.cognitiveservices.knowledge.qnamaker.models.QnASearchResultList;
import com.microsoft.azure.cognitiveservices.knowledge.qnamaker.models.QueryDTO;
import java.io.IOException;
import java.util.List;
import rx.Observable;

/**
 * An instance of this class provides access to all the operations defined
 * in Runtimes.
 */
public interface Runtimes {

    /**
     * GenerateAnswer call to query the knowledgebase.
     *
     * @param kbId Knowledgebase id.
     * @param generateAnswerPayload Post body of the request.
     * @throws IllegalArgumentException thrown if parameters fail the validation
     * @throws ErrorResponseException thrown if the request is rejected by server
     * @throws RuntimeException all other wrapped checked exceptions if the request fails to be sent
     * @return the QnASearchResultList object if successful.
     */
    QnASearchResultList generateAnswer(String kbId, QueryDTO generateAnswerPayload);

    /**
     * GenerateAnswer call to query the knowledgebase.
     *
     * @param kbId Knowledgebase id.
     * @param generateAnswerPayload Post body of the request.
     * @throws IllegalArgumentException thrown if parameters fail the validation
     * @return the observable to the QnASearchResultList object
     */
    Observable<QnASearchResultList> generateAnswerAsync(String kbId, QueryDTO generateAnswerPayload);


    /**
     * Train call to add suggestions to the knowledgebase.
     *
     * @param kbId Knowledgebase id.
     * @param trainOptionalParameter the object representing the optional parameters to be set before calling this API
     * @throws IllegalArgumentException thrown if parameters fail the validation
     * @throws ErrorResponseException thrown if the request is rejected by server
     * @throws RuntimeException all other wrapped checked exceptions if the request fails to be sent
     */
    void train(String kbId, TrainOptionalParameter trainOptionalParameter);

    /**
     * Train call to add suggestions to the knowledgebase.
     *
     * @param kbId Knowledgebase id.
     * @param trainOptionalParameter the object representing the optional parameters to be set before calling this API
     * @throws IllegalArgumentException thrown if parameters fail the validation
     * @return a representation of the deferred computation of this call if successful.
     */
    Observable<Void> trainAsync(String kbId, TrainOptionalParameter trainOptionalParameter);

    /**
     * Train call to add suggestions to the knowledgebase.
     *
     * @return the first stage of the train call
     */
    RuntimesTrainDefinitionStages.WithKbId train();

    /**
     * Grouping of train definition stages.
     */
    interface RuntimesTrainDefinitionStages {
        /**
         * The stage of the definition to be specify kbId.
         */
        interface WithKbId {
            /**
             * Knowledgebase id.
             *
             * @return next definition stage
             */
            RuntimesTrainDefinitionStages.WithExecute withKbId(String kbId);
        }

        /**
         * The stage of the definition which allows for any other optional settings to be specified.
         */
        interface WithAllOptions {
            /**
             * List of feedback records.
             *
             * @return next definition stage
             */
            RuntimesTrainDefinitionStages.WithExecute withFeedbackRecords(List<FeedbackRecordDTO> feedbackRecords);

        }

        /**
         * The last stage of the definition which will make the operation call.
        */
        interface WithExecute extends RuntimesTrainDefinitionStages.WithAllOptions {
            /**
             * Execute the request.
             *
             */
            void execute();

            /**
             * Execute the request asynchronously.
             *
             * @return a representation of the deferred computation of this call if successful.
             */
            Observable<Void> executeAsync();
        }
    }

    /**
     * The entirety of train definition.
     */
    interface RuntimesTrainDefinition extends
        RuntimesTrainDefinitionStages.WithKbId,
        RuntimesTrainDefinitionStages.WithExecute {
    }

}
